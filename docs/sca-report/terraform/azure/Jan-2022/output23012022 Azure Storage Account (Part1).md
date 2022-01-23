# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Jan 2022)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20AKS.md
#### Application Gateway: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20Application%20Gateway.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20SQL%20Servers.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Jan-2022/output23012022%20Azure%20VM.md

## Terraform Azure Storage Account (Part1) Services

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1642942644224                      |
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet_nat_gateway_association', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_nat_gateway_public_ip_association', 'azurerm_public_ip', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/main.tf']                                                                                                                                                              |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_asset', 'azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT95                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_redis_cache', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_share', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT128                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT132                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_template_deployment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_network_interface', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT160                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_windows_virtual_machine', 'azurerm_storage_account', 'azurerm_resource_group']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_network_interface', 'azurerm_firewall_application_rule_collection', 'azurerm_route_table', 'azurerm_network_interface_security_group_association', 'azurerm_firewall', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'random_string', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_firewall_network_rule_collection', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| id            | TRF_TEMPLATE_SNAPSHOT196                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-003
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet_nat_gateway_association', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_nat_gateway_public_ip_association', 'azurerm_public_ip', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/main.tf']                                                                                                                                                              |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_asset', 'azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT95                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_redis_cache', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_share', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT128                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT132                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_template_deployment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_network_interface', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
- eval: [{'id': 'PR-AZR-TRF-STR-004', 'eval': 'data.rule.storage_acl', 'message': 'data.rule.storage_acl_err', 'remediationDescription': "In 'azurerm_storage_account_network_rules' resource or 'azurerm_storage_account's inner block 'network_rules', set 'default_action = Deny' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_004.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT160                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_windows_virtual_machine', 'azurerm_storage_account', 'azurerm_resource_group']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_network_interface', 'azurerm_firewall_application_rule_collection', 'azurerm_route_table', 'azurerm_network_interface_security_group_association', 'azurerm_firewall', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'random_string', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_firewall_network_rule_collection', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| id            | TRF_TEMPLATE_SNAPSHOT196                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-004
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet_nat_gateway_association', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_nat_gateway_public_ip_association', 'azurerm_public_ip', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/main.tf']                                                                                                                                                              |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_asset', 'azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT95                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_redis_cache', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_share', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT128                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT132                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_template_deployment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_network_interface', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT160                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_windows_virtual_machine', 'azurerm_storage_account', 'azurerm_resource_group']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_network_interface', 'azurerm_firewall_application_rule_collection', 'azurerm_route_table', 'azurerm_network_interface_security_group_association', 'azurerm_firewall', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'random_string', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_firewall_network_rule_collection', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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
| id            | TRF_TEMPLATE_SNAPSHOT196                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-005
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


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet_nat_gateway_association', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_nat_gateway_public_ip_association', 'azurerm_public_ip', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/main.tf']                                                                                                                                                              |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_asset', 'azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT95                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_redis_cache', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_share', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT128                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT132                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_template_deployment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_network_interface', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - 
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-008', 'eval': 'data.rule.keySource', 'message': 'data.rule.keySource_err', 'remediationDescription': "In 'azurerm_storage_encryption_scope' resource, set 'source = microsoft.keyvault' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_encryption_scope#source' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_008.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT160                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_windows_virtual_machine', 'azurerm_storage_account', 'azurerm_resource_group']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_network_interface', 'azurerm_firewall_application_rule_collection', 'azurerm_route_table', 'azurerm_network_interface_security_group_association', 'azurerm_firewall', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'random_string', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_firewall_network_rule_collection', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-008
Title: Ensure critical data storage in Storage Account is encrypted with Customer Managed Key\
Test Result: **failed**\
Description : By default, data in the storage account is encrypted using Microsoft Managed Keys at rest. All Azure Storage resources are encrypted, including blobs, disks, files, queues, and tables. All object metadata is also encrypted. However, if you want to control and manage this encryption key yourself, you can specify a customer-managed key, that key is used to protect and control access to the key that encrypts your data. You can also choose to automatically update the key version used for Azure Storage encryption whenever a new version is available in the associated Key Vault.\

#### Test Details
- eval: data.rule.keySource
- id : PR-AZR-TRF-STR-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT196                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-008
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['terraform']     |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet_nat_gateway_association', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_nat_gateway_public_ip_association', 'azurerm_public_ip', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/main.tf']                                                                                                                                                              |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_asset', 'azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT95                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_redis_cache', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_share', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT128                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT132                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_template_deployment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_network_interface', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - 
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-009', 'eval': 'data.rule.region', 'message': 'data.rule.region_err', 'remediationDescription': "In 'azurerm_storage_account' resource, set value as 'northeurope' or 'westeurope' in property 'location' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#location' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_009.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                          |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT160                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_windows_virtual_machine', 'azurerm_storage_account', 'azurerm_resource_group']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_network_interface', 'azurerm_firewall_application_rule_collection', 'azurerm_route_table', 'azurerm_network_interface_security_group_association', 'azurerm_firewall', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'random_string', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_firewall_network_rule_collection', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-009
Title: Storage Accounts location configuration should be inside of Europe\
Test Result: **failed**\
Description : Identify Storage Accounts outside of the following regions: northeurope, westeurope\

#### Test Details
- eval: data.rule.region
- id : PR-AZR-TRF-STR-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT196                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-009
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: High

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | ['GDPR']      |
| service    | ['terraform'] |
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT49                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_subnet_network_security_group_association', 'azurerm_network_security_group', 'azurerm_subnet_nat_gateway_association', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_nat_gateway_public_ip_association', 'azurerm_public_ip', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-hbase-cluster/main.tf']                                                                                                                                                              |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT72                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_asset', 'azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_media_services_account', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT95                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_redis_cache', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/redis-cache/premium-with-backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT101                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                      |
| reference     | main                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                 |
| collection    | terraformtemplate                                                                                                                                                                                                                                                               |
| type          | terraform                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_virtual_network']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-account/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT113                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_storage_share', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                            |
| reference     | main                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                       |
| collection    | terraformtemplate                                                                                                                                                                                                                     |
| type          | terraform                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                       |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT116                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_stream_analytics_reference_input_blob']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT128                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_network_interface_nat_rule_association', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT132                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                          |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_template_deployment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT144                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_network_interface', 'azurerm_lb_rule', 'azurerm_lb', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_virtual_network', 'azurerm_lb_probe', 'azurerm_subnet', 'azurerm_lb_backend_address_pool', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_lb_nat_rule', 'azurerm_public_ip']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT150                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT151                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_network_interface', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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

- masterTestId: PR-AZR-TRF-STR-010
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
| id            | TRF_TEMPLATE_SNAPSHOT160                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                           |
| reference     | main                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                      |
| collection    | terraformtemplate                                                                                                                                                                                                                                                    |
| type          | terraform                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                      |
| resourceTypes | ['azurerm_network_interface', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_windows_virtual_machine', 'azurerm_storage_account', 'azurerm_resource_group']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT161                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_network_interface', 'azurerm_firewall_application_rule_collection', 'azurerm_route_table', 'azurerm_network_interface_security_group_association', 'azurerm_firewall', 'azurerm_virtual_machine', 'azurerm_network_security_group', 'random_string', 'azurerm_subnet_route_table_association', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_firewall_network_rule_collection', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: PR-AZR-TRF-STR-010
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
| Title         | Description                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT175                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT196                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | main                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                               |
| collection    | terraformtemplate                                                                                                                                                                                                                                             |
| type          | terraform                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-010
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
Title: Storage Accounts queue service logging should be enabled\
Test Result: **failed**\
Description : The Azure Storage Queue service logging records details for both successful and failed requests made to the queues, as well as end-to-end latency, server latency, and authentication information.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-014', 'eval': 'data.rule.storage_account_queue_logging_enabled_for_all_operation', 'message': 'data.rule.storage_account_queue_logging_enabled_for_all_operation_err', 'remediationDescription': "In 'azurerm_storage_account' resource, set 'read = true', 'write = true', 'delete = true' under 'logging' block which exist under 'queue_properties' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#logging' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_014.py'}]
- id : 

#### Snapshots
[]

- masterTestId: PR-AZR-TRF-STR-014
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_storage_container', 'azurerm_app_service', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

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
| resourceTypes | ['azurerm_app_service_plan', 'azurerm_application_insights', 'azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_app_service_plan']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

#### Snapshots
| Title         | Description                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT26                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                |
| reference     | main                                                                                                                                                                                                      |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                           |
| collection    | terraformtemplate                                                                                                                                                                                         |
| type          | terraform                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                           |
| resourceTypes | ['azurerm_batch_account', 'azurerm_storage_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                  |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT27                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                   |
| reference     | main                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                              |
| collection    | terraformtemplate                                                                                                                                                                                                                                                            |
| type          | terraform                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                              |
| resourceTypes | ['azurerm_network_interface', 'azurerm_batch_pool', 'azurerm_image', 'azurerm_virtual_machine', 'azurerm_storage_container', 'azurerm_virtual_network', 'azurerm_subnet', 'azurerm_batch_account', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_public_ip'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                            |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT29                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                             |
| reference     | main                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                        |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                      |
| type          | terraform                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                        |
| resourceTypes | ['azurerm_cdn_endpoint', 'azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT33                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                 |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                       |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                            |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                          |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['azurerm_storage_share', 'azurerm_container_group', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT45                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_storage_queue', 'azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_eventgrid_event_subscription']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-011
Title: Storage Accounts access should be allowed for trusted Microsoft services\
Test Result: **failed**\
Description : Ensure that 'Allow trusted Microsoft services to access this storage account' exception is enabled within your Azure Storage account configuration settings to grant access to trusted cloud services.\

#### Test Details
- eval: data.rule.storage_nr_allow_trusted_azure_services
- id : PR-AZR-TRF-STR-011

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT48                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['azurerm_user_assigned_identity', 'azurerm_subnet_network_security_group_association', 'azuread_group', 'azurerm_network_security_group', 'azurerm_active_directory_domain_service', 'azurerm_storage_container', 'azuread_user', 'azurerm_virtual_network_dns_servers', 'azurerm_virtual_network', 'azurerm_role_assignment', 'azurerm_subnet', 'azurerm_storage_account', 'azurerm_resource_group', 'azurerm_hdinsight_hadoop_cluster', 'azuread_group_member'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: PR-AZR-TRF-STR-011
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageaccounts.rego)
- severity: Medium

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['CIS', 'HIPAA', 'NIST 800', 'PCI-DSS'] |
| service    | ['terraform']                           |
----------------------------------------------------------------

