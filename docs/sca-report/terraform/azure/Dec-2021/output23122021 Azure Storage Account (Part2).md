# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Dec 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20AKS.md
#### Application Gateway: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Application%20Gateway.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20SQL%20Servers.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Dec-2021/output23122021%20Azure%20VM.md

## Terraform Azure Storage Account Services (Part2)

Source Repository: https://github.com/hashicorp/terraform-provider-azurerm

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/

## Compliance run Meta Data
| Title     | Description                        |
|:----------|:-----------------------------------|
| timestamp | 1640200946958                      |
| snapshot  | master-snapshot_gen                |
| container | scenario-azure-terraform-hashicorp |
| test      | master-test.json                   |

## Results

### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_app_service_plan', 'azurerm_resource_group']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_container_group', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_user_assigned_identity', 'azurerm_public_ip', 'azurerm_nat_gateway_public_ip_association'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_media_asset', 'azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_subnet', 'azurerm_virtual_network', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface_nat_rule_association', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - 
Title: Ensure Storage Account naming rules are correct\
Test Result: **failed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-017', 'eval': 'data.rule.storage_correct_naming_convention', 'message': 'data.rule.storage_correct_naming_convention_err', 'remediationDescription': "In 'azurerm_storage_account' resource, property 'name' must be between 3 and 24 characters in length and may contain numbers and lowercase letters only to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#name' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_017.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_windows_virtual_machine', 'azurerm_network_interface']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_route_table', 'azurerm_virtual_network', 'azurerm_firewall_network_rule_collection', 'azurerm_network_interface_security_group_association', 'azurerm_subnet', 'azurerm_subnet_route_table_association', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_firewall_application_rule_collection', 'random_string', 'azurerm_network_interface', 'azurerm_firewall', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_linux_virtual_machine_scale_set']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-017
Title: Ensure Storage Account naming rules are correct\
Test Result: **passed**\
Description : Storage account names must be between 3 and 24 characters in length and may contain numbers and lowercase letters only.\

#### Test Details
- eval: data.rule.storage_correct_naming_convention
- id : PR-AZR-TRF-STR-017

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_11
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_app_service_plan', 'azurerm_resource_group']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_container_group', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_user_assigned_identity', 'azurerm_public_ip', 'azurerm_nat_gateway_public_ip_association'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_media_asset', 'azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_subnet', 'azurerm_virtual_network', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface_nat_rule_association', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-018', 'eval': 'data.rule.storage_account_latest_tls_configured', 'message': 'data.rule.storage_account_latest_tls_configured_err', 'remediationDescription': "In 'azurerm_storage_account' resource, set min_tls_version = 'TLS1_2' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_018.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_windows_virtual_machine', 'azurerm_network_interface']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_route_table', 'azurerm_virtual_network', 'azurerm_firewall_network_rule_collection', 'azurerm_network_interface_security_group_association', 'azurerm_subnet', 'azurerm_subnet_route_table_association', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_firewall_application_rule_collection', 'random_string', 'azurerm_network_interface', 'azurerm_firewall', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_linux_virtual_machine_scale_set']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-018
Title: Ensure Azure Storage Account has latest version of tls configured\
Test Result: **failed**\
Description : This policy will identify the Azure Storage Account which dont have latest version of tls configured and give alert\

#### Test Details
- eval: data.rule.storage_account_latest_tls_configured
- id : PR-AZR-TRF-STR-018

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_12
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_app_service_plan', 'azurerm_resource_group']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_container_group', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_user_assigned_identity', 'azurerm_public_ip', 'azurerm_nat_gateway_public_ip_association'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_media_asset', 'azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_subnet', 'azurerm_virtual_network', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface_nat_rule_association', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-019', 'eval': 'data.rule.storage_account_uses_privatelink', 'message': 'data.rule.storage_account_uses_privatelink_err', 'remediationDescription': "'azurerm_storage_account' resource need to have a link with 'azurerm_private_endpoint', set 'id' of 'azurerm_storage_account' to property 'private_connection_resource_id' under 'azurerm_private_endpoint' resources 'private_service_connection' block to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint#private_connection_resource_id' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_019.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_windows_virtual_machine', 'azurerm_network_interface']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_route_table', 'azurerm_virtual_network', 'azurerm_firewall_network_rule_collection', 'azurerm_network_interface_security_group_association', 'azurerm_subnet', 'azurerm_subnet_route_table_association', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_firewall_application_rule_collection', 'random_string', 'azurerm_network_interface', 'azurerm_firewall', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_linux_virtual_machine_scale_set']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-019
Title: Azure Storage account should use private link\
Test Result: **failed**\
Description : Private endpoints lets you connect your virtual network to Azure services without a public IP address at the source or destination. By mapping private endpoints to your Azure Storage account instances, data leakage risks are reduced.\

#### Test Details
- eval: data.rule.storage_account_uses_privatelink
- id : PR-AZR-TRF-STR-019

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_13
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_app_service_plan', 'azurerm_resource_group']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_container_group', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_user_assigned_identity', 'azurerm_public_ip', 'azurerm_nat_gateway_public_ip_association'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_media_asset', 'azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_subnet', 'azurerm_virtual_network', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface_nat_rule_association', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-020', 'eval': 'data.rule.storage_account_uses_double_encryption', 'message': 'data.rule.storage_account_uses_double_encryption_err', 'remediationDescription': "'azurerm_storage_account' resource need to have a link with 'azurerm_storage_encryption_scope', set 'id' of 'azurerm_storage_account' to property 'storage_account_id' under 'azurerm_storage_encryption_scope' resource to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_encryption_scope#storage_account_id' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_020.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_windows_virtual_machine', 'azurerm_network_interface']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_route_table', 'azurerm_virtual_network', 'azurerm_firewall_network_rule_collection', 'azurerm_network_interface_security_group_association', 'azurerm_subnet', 'azurerm_subnet_route_table_association', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_firewall_application_rule_collection', 'random_string', 'azurerm_network_interface', 'azurerm_firewall', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_linux_virtual_machine_scale_set']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-020
Title: Storage account encryption scopes should use double encryption for data at rest\
Test Result: **failed**\
Description : Enable infrastructure encryption for encryption at rest of your storage account encryption scopes for added security. Infrastructure encryption ensures that your data is encrypted twice.\

#### Test Details
- eval: data.rule.storage_account_uses_double_encryption
- id : PR-AZR-TRF-STR-020

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_14
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_app_service_plan', 'azurerm_resource_group']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_container_group', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_user_assigned_identity', 'azurerm_public_ip', 'azurerm_nat_gateway_public_ip_association'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_media_asset', 'azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_subnet', 'azurerm_virtual_network', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface_nat_rule_association', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-024', 'eval': 'data.rule.storage_shared_access_key_disabled', 'message': 'data.rule.storage_shared_access_key_disabled_err', 'remediationDescription': "In 'azurerm_storage_account' resource, set 'shared_access_key_enabled = false' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#shared_access_key_enabled' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_024.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_windows_virtual_machine', 'azurerm_network_interface']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_route_table', 'azurerm_virtual_network', 'azurerm_firewall_network_rule_collection', 'azurerm_network_interface_security_group_association', 'azurerm_subnet', 'azurerm_subnet_route_table_association', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_firewall_application_rule_collection', 'random_string', 'azurerm_network_interface', 'azurerm_firewall', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_linux_virtual_machine_scale_set']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-024
Title: Storage accounts should prevent shared key access\
Test Result: **failed**\
Description : Audit requirement of Azure Active Directory (Azure AD) to authorize requests for your storage account. By default, requests can be authorized with either Azure Active Directory credentials, or by using the account access key for Shared Key authorization. Of these two types of authorization, Azure AD provides superior security and ease of use over Shared Key, and is recommended by Microsoft.\

#### Test Details
- eval: data.rule.storage_shared_access_key_disabled
- id : PR-AZR-TRF-STR-024

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_15
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-azure-RBAC-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_function_app', 'azurerm_application_insights', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_function_app', 'azurerm_storage_account', 'azurerm_app_service_plan', 'azurerm_resource_group']                                                                                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/function-python/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_batch_account', 'azurerm_batch_pool', 'azurerm_resource_group']                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_cdn_profile', 'azurerm_storage_account', 'azurerm_cdn_endpoint', 'azurerm_resource_group']                                                                                                                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cdn/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_container_group', 'azurerm_resource_group']                                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/container-instance/volume-mount/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_nat_gateway', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azurerm_subnet_nat_gateway_association', 'azurerm_storage_data_lake_gen2_filesystem', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_user_assigned_identity', 'azurerm_public_ip', 'azurerm_nat_gateway_public_ip_association'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/private-link/hadoop-interactive-spark-cluster/main.tf']                                                                                                                                                                          |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_media_asset', 'azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                      |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/basic-with-assets/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_media_services_account', 'azurerm_resource_group']                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/media-services/multiple-storage-accounts/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_subnet', 'azurerm_virtual_network', 'azurerm_storage_account', 'azurerm_resource_group']                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/0-base.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_share', 'azurerm_resource_group']                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-share/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_data_lake_gen2_filesystem', 'azurerm_storage_data_lake_gen2_path', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_user_assigned_identity']                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage_adls_acls/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface_nat_rule_association', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                                   |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/2-vms-loadbalancer-lbrules/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_template_deployment', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/encrypt-running-linux-vm/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_subnet', 'azurerm_lb_nat_rule', 'azurerm_virtual_machine', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_lb_rule', 'azurerm_public_ip', 'azurerm_lb_backend_address_pool', 'azurerm_network_interface', 'azurerm_lb_probe', 'azurerm_lb']                                                                     |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/openshift-origin/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: [{'id': 'PR-AZR-TRF-STR-023', 'eval': 'data.rule.storage_acl_usage_vnet', 'message': 'data.rule.storage_acl_usage_vnet_err', 'remediationDescription': "In 'azurerm_storage_account_network_rules' resource or 'azurerm_storage_account's inner block 'network_rules', set 'default_action = Deny' and set id of target 'azurerm_subnet' into property 'virtual_network_subnet_ids' to fix the issue. Visit <a href='https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#virtual_network_subnet_ids' target='_blank'>here</a> for details.", 'remediationFunction': 'PR_AZR_TRF_STR_023.py'}]
- id : 

#### Snapshots
[]

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_role_assignment', 'azurerm_storage_account', 'azurerm_windows_virtual_machine', 'azurerm_network_interface']                                                                        |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/vars.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/windows/vm-role-assignment/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_route_table', 'azurerm_virtual_network', 'azurerm_firewall_network_rule_collection', 'azurerm_network_interface_security_group_association', 'azurerm_subnet', 'azurerm_subnet_route_table_association', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_firewall_application_rule_collection', 'random_string', 'azurerm_network_interface', 'azurerm_firewall', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-networks/azure-firewall/main.tf']                                                                                                                                                                                                                           |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_linux_virtual_machine_scale_set']                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-023
Title: Storage Accounts should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Storage Account not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.storage_acl_usage_vnet
- id : PR-AZR-TRF-STR-023

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_windows_virtual_machine_scale_set']                                                                                                               |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/boot-diagnostics/main.tf'] |

- masterTestId: TEST_STORAGE_ACCOUNT_16
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


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **passed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_app_service', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_app_service_plan']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/output.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service/backup/main.tf'] |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **failed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_image', 'azurerm_resource_group', 'azurerm_batch_pool', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_batch_account', 'azurerm_virtual_machine'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/batch/custom-image/main.tf']                                                      |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **passed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_storage_blob', 'azurerm_storage_container', 'azurerm_eventgrid_event_subscription', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_storage_queue']                                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/eventgrid/event-subscription/main.tf'] |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **passed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_hdinsight_hadoop_cluster', 'azurerm_subnet', 'azuread_user', 'azurerm_resource_group', 'azurerm_subnet_network_security_group_association', 'azurerm_storage_account', 'azurerm_role_assignment', 'azurerm_active_directory_domain_service', 'azurerm_user_assigned_identity', 'azuread_group_member', 'azuread_group', 'azurerm_virtual_network_dns_servers'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/providers.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/hdinsight/enterprise-security-package/main.tf']                                                                     |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **failed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_storage_account', 'azurerm_storage_container', 'azurerm_resource_group']                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/storage/storage-container/main.tf'] |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **passed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_storage_container', 'azurerm_stream_analytics_job', 'azurerm_stream_analytics_reference_input_blob', 'azurerm_resource_group', 'azurerm_storage_account']                                                 |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/stream-analytics/main.tf'] |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **passed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_network_security_group', 'azurerm_virtual_network', 'azurerm_availability_set', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_public_ip', 'azurerm_network_interface', 'azurerm_virtual_machine']                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/spark-and-cassandra-on-centos/main.tf'] |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-STR-012
Title: Azure storage blob container should not have public access enabled\
Test Result: **passed**\
Description : 'Public access level' allows you to grant anonymous/public read access to a container and the blobs within Azure blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature.<br><br>This policy identifies blob containers within an Azure storage account that allow anonymous/public access ('CONTAINER' or 'BLOB') that also have Audit Log Retention set to less than 180 days.<br><br>As a best practice, do not allow anonymous/public access to blob containers unless you have a very good reason. Instead, you should consider using a shared access signature token for providing controlled and time-limited access to blob containers.\

#### Test Details
- eval: data.rule.storage_container_public_access_disabled
- id : PR-AZR-TRF-STR-012

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
| resourceTypes | ['azurerm_virtual_network', 'azurerm_storage_container', 'azurerm_subnet', 'azurerm_resource_group', 'azurerm_storage_account', 'azurerm_network_interface']                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/unmanaged-disks/basic/1-dependencies.tf'] |

- masterTestId: TEST_STORAGE_BLOB_CONTAINER
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/storageblobcontainers.rego)
- severity: High

tags
| Title      | Description                                           |
|:-----------|:------------------------------------------------------|
| cloud      | git                                                   |
| compliance | ['CIS', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['terraform']                                         |
----------------------------------------------------------------

