# Automated Vulnerability Scan result and Static Code Analysis for Terraform Provider AZURE (Nov 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20AKS.md
#### KeyVault: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20KeyVault.md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20SQL%20Servers.md
#### Storage Account (Part1): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part1).md
#### Storage Account (Part2): https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20Storage%20Account%20(Part2).md
#### VM: https://github.com/prancer-io/prancer-compliance-test/blob/master/docs/sca-report/terraform/azure/Nov/output11182021%20Azure%20VM.md

## Terraform Azure KeyVault Services 

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

### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_app_service_certificate', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_certificate']                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service-certificate/stored-in-keyvault/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service-certificate/stored-in-keyvault/main.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_resource_group', 'azurerm_cosmosdb_account', 'azurerm_key_vault', 'azurerm_key_vault_key']                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/main.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key']                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/main.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT38                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key']                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/main.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_resource_group', 'azurerm_key_vault']                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/1-dependencies.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_private_dns_cname_record', 'azurerm_subnet_network_security_group_association', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key', 'azurerm_private_dns_zone', 'azurerm_private_endpoint', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/main.tf']                                                                                                                                                      |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/1-keyvault.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT143                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/2-certificates.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT178                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_key_vault_certificate']                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/main.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT201                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet', 'azurerm_windows_virtual_machine_scale_set', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_key_vault_certificate']                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/secrets/main.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-001
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-TRF-KV-001

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT203                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/service-fabric/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/service-fabric/2-key-vault.tf'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['terraform']                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_app_service_certificate', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_certificate']                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service-certificate/stored-in-keyvault/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service-certificate/stored-in-keyvault/main.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_resource_group', 'azurerm_cosmosdb_account', 'azurerm_key_vault', 'azurerm_key_vault_key']                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/main.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key']                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/main.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT38                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key']                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/main.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_resource_group', 'azurerm_key_vault']                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/1-dependencies.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_private_dns_cname_record', 'azurerm_subnet_network_security_group_association', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key', 'azurerm_private_dns_zone', 'azurerm_private_endpoint', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/main.tf']                                                                                                                                                      |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/1-keyvault.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT143                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/2-certificates.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT178                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_key_vault_certificate']                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/main.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT201                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet', 'azurerm_windows_virtual_machine_scale_set', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_key_vault_certificate']                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/secrets/main.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-TRF-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT203                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/service-fabric/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/service-fabric/2-key-vault.tf'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT18                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_app_service_certificate', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_certificate']                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service-certificate/stored-in-keyvault/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/app-service-certificate/stored-in-keyvault/main.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_resource_group', 'azurerm_cosmosdb_account', 'azurerm_key_vault', 'azurerm_key_vault_key']                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/main.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key']                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/main.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT38                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key']                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/main.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_resource_group', 'azurerm_key_vault']                                                                                                                                                                                             |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/1-dependencies.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_private_dns_cname_record', 'azurerm_subnet_network_security_group_association', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key', 'azurerm_private_dns_zone', 'azurerm_private_endpoint', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/main.tf']                                                                                                                                                      |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                                              |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/service-fabric/windows-vmss-self-signed-certs/1-keyvault.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT143                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/virtual-machines/virtual_machine/provisioners/windows/2-certificates.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT178                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_linux_virtual_machine_scale_set', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_key_vault_certificate']                                                                |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/linux/secrets/main.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT201                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_subnet', 'azurerm_windows_virtual_machine_scale_set', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_key_vault_certificate']                                                                  |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/secrets/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/secrets/main.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-002
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-TRF-KV-002

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                      |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT203                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_key_vault_certificate', 'azurerm_key_vault']                                                                                                                                                                                                           |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/service-fabric/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/vm-scale-set/windows/service-fabric/2-key-vault.tf'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['terraform']       |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiry date. As a best practice, set an expiration date for each secret and rotate the secret regularly.<br><br>Before you activate this policy, ensure that you have added the <compliance-software> Service Principal to each Key Vault: https://docs.paloaltonetworks.com/<compliance-software>/<compliance-software>-admin/connect-your-cloud-platform-to-<compliance-software>/onboard-your-azure-account/set-up-your-azure-account.html<br><br>Alternatively, run the following command on the Azure cloud shell:<br>az keyvault list | jq '.[].name' | xargs -I {} az keyvault set-policy --name {} --certificate-permissions list listissuers --key-permissions list --secret-permissions list --spn <<compliance-software>_app_id>\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-TRF-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT34                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                              |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                         |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                       |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['azurerm_resource_group', 'azurerm_cosmosdb_account', 'azurerm_key_vault', 'azurerm_key_vault_key']                                                                                                                                                                                                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/outputs.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/cosmos-db/customer-managed-key/main.tf'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['terraform']                                                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiry date. As a best practice, set an expiration date for each secret and rotate the secret regularly.<br><br>Before you activate this policy, ensure that you have added the <compliance-software> Service Principal to each Key Vault: https://docs.paloaltonetworks.com/<compliance-software>/<compliance-software>-admin/connect-your-cloud-platform-to-<compliance-software>/onboard-your-azure-account/set-up-your-azure-account.html<br><br>Alternatively, run the following command on the Azure cloud shell:<br>az keyvault list | jq '.[].name' | xargs -I {} az keyvault set-policy --name {} --certificate-permissions list listissuers --key-permissions list --secret-permissions list --spn <<compliance-software>_app_id>\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-TRF-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT37                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                  |
| reference     | main                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                             |
| collection    | terraformtemplate                                                                                                                                                                                                                                           |
| type          | terraform                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                             |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key']                                                            |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/dbfs/main.tf'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['terraform']                                                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiry date. As a best practice, set an expiration date for each secret and rotate the secret regularly.<br><br>Before you activate this policy, ensure that you have added the <compliance-software> Service Principal to each Key Vault: https://docs.paloaltonetworks.com/<compliance-software>/<compliance-software>-admin/connect-your-cloud-platform-to-<compliance-software>/onboard-your-azure-account/set-up-your-azure-account.html<br><br>Alternatively, run the following command on the Azure cloud shell:<br>az keyvault list | jq '.[].name' | xargs -I {} az keyvault set-policy --name {} --certificate-permissions list listissuers --key-permissions list --secret-permissions list --spn <<compliance-software>_app_id>\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-TRF-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT38                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | main                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                     |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                   |
| type          | terraform                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['azurerm_key_vault', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key']                                                                                                                                         |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/databricks/customer-managed-key/managed-services/main.tf'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['terraform']                                                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiry date. As a best practice, set an expiration date for each secret and rotate the secret regularly.<br><br>Before you activate this policy, ensure that you have added the <compliance-software> Service Principal to each Key Vault: https://docs.paloaltonetworks.com/<compliance-software>/<compliance-software>-admin/connect-your-cloud-platform-to-<compliance-software>/onboard-your-azure-account/set-up-your-azure-account.html<br><br>Alternatively, run the following command on the Azure cloud shell:<br>az keyvault list | jq '.[].name' | xargs -I {} az keyvault set-policy --name {} --certificate-permissions list listissuers --key-permissions list --secret-permissions list --spn <<compliance-software>_app_id>\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-TRF-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT68                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                        |
| reference     | main                                                                                                                                                                                                                              |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                   |
| collection    | terraformtemplate                                                                                                                                                                                                                 |
| type          | terraform                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                   |
| resourceTypes | ['azurerm_disk_encryption_set', 'azurerm_role_assignment', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_managed_disk']                                                                                    |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/managed-disks/encrypted/main.tf'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['terraform']                                                           |
----------------------------------------------------------------


### Test ID - PR-AZR-TRF-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiry date. As a best practice, set an expiration date for each secret and rotate the secret regularly.<br><br>Before you activate this policy, ensure that you have added the <compliance-software> Service Principal to each Key Vault: https://docs.paloaltonetworks.com/<compliance-software>/<compliance-software>-admin/connect-your-cloud-platform-to-<compliance-software>/onboard-your-azure-account/set-up-your-azure-account.html<br><br>Alternatively, run the following command on the Azure cloud shell:<br>az keyvault list | jq '.[].name' | xargs -I {} az keyvault set-policy --name {} --certificate-permissions list listissuers --key-permissions list --secret-permissions list --spn <<compliance-software>_app_id>\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-TRF-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | TRF_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                       |
| reference     | main                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureTerraHashicorp                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | terraformtemplate                                                                                                                                                                                                                                                                                                                                                                                                                |
| type          | terraform                                                                                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['azurerm_private_dns_cname_record', 'azurerm_subnet_network_security_group_association', 'azurerm_subnet', 'azurerm_key_vault', 'azurerm_virtual_network', 'azurerm_resource_group', 'azurerm_databricks_workspace', 'azurerm_key_vault_access_policy', 'azurerm_key_vault_key', 'azurerm_databricks_workspace_customer_managed_key', 'azurerm_private_dns_zone', 'azurerm_private_endpoint', 'azurerm_network_security_group'] |
| paths         | ['https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/variables.tf', 'https://github.com/hashicorp/terraform-provider-azurerm/tree/main/examples/private-endpoint/databricks/managed-services/main.tf']                                                                                                                                                      |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['TRF_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/terraform/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['terraform']                                                           |
----------------------------------------------------------------

