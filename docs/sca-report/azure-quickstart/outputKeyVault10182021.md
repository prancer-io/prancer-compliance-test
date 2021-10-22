# Automated Vulnerability Scan result and Static Code Analysis for Azure Quickstart files (Oct 2021)


## Azure Key Vault Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description               |
|:----------|:--------------------------|
| timestamp | 1634565847663             |
| snapshot  | master-snapshot_gen       |
| container | scenario-azure-quickstart |
| test      | master-test.json          |

## Results

### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT52                                                                                                                      |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-automate-ha/nested/keyvaultResource.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT507                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT784                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.containerservice/managedclusters', 'microsoft.storage/storageaccounts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.insights/activitylogalerts', 'microsoft.operationsmanagement/solutions', 'microsoft.authorization/roleassignments', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT811                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT901                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT903                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT921                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.apimanagement/service', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1017                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1018                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1026                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1028                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1035                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1370                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1371                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1372                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1375                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.insights/diagnosticsettings', 'microsoft.authorization/locks']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1376                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1400                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1402                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1404                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1406                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1408                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1410                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1412                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1414                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1416                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1418                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.machinelearningservices/workspaces/datasets']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1425                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1427                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1429                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1431                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1433                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1435                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerregistry/registries', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.synapse/workspaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1442                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces/computes', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1446                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1447                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1449                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1450                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1451                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.resources/deployments']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1453                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.resources/deployments']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1462                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.containerservice/managedclusters', 'microsoft.storage/storageaccounts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.insights/activitylogalerts', 'microsoft.operationsmanagement/solutions', 'microsoft.authorization/roleassignments', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/azurefirewalls', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/firewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/routetables', 'microsoft.resources/deploymentscripts', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1716                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks/subnets', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/sites/config', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1729                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites/functions', 'microsoft.web/sites']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0107-ARM
Title: Ensure at least one principal has access to Keyvault\
Test Result: **passed**\
Description : Use the Azure Key Vault to store secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each.\

#### Test Details
- eval: data.rule.KeyVault
- id : PR-AZR-0107-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KeyVault_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Low

tags
| Title      | Description                             |
|:-----------|:----------------------------------------|
| cloud      | git                                     |
| compliance | ['Best Practices', 'HIPAA', 'NIST CSF'] |
| service    | ['arm']                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT52                                                                                                                      |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-automate-ha/nested/keyvaultResource.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT507                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT784                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.containerservice/managedclusters', 'microsoft.storage/storageaccounts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.insights/activitylogalerts', 'microsoft.operationsmanagement/solutions', 'microsoft.authorization/roleassignments', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT811                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT901                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT903                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT921                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.apimanagement/service', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1017                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1018                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1026                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1028                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1035                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1370                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1371                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1372                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1375                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.insights/diagnosticsettings', 'microsoft.authorization/locks']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1376                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1400                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1402                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1404                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1406                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1408                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1410                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1412                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1414                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1416                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1418                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.machinelearningservices/workspaces/datasets']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1425                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1427                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1429                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1431                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1433                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1435                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerregistry/registries', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.synapse/workspaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1442                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces/computes', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1446                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1447                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1449                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1450                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1451                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.resources/deployments']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1453                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.resources/deployments']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1462                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.containerservice/managedclusters', 'microsoft.storage/storageaccounts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.insights/activitylogalerts', 'microsoft.operationsmanagement/solutions', 'microsoft.authorization/roleassignments', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/azurefirewalls', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/firewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/routetables', 'microsoft.resources/deploymentscripts', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1716                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks/subnets', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/sites/config', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1729                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites/functions', 'microsoft.web/sites']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0108-ARM
Title: Ensure the key vault is recoverable - enable 'Soft Delete' setting for a Key Vault\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KeyVault_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT52                                                                                                                      |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorAzureQuickStart                                                                                                                  |
| collection    | armtemplate                                                                                                                                  |
| type          | arm                                                                                                                                          |
| region        |                                                                                                                                              |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/chef/chef-automate-ha/nested/keyvaultResource.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT507                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT784                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.containerservice/managedclusters', 'microsoft.storage/storageaccounts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.insights/activitylogalerts', 'microsoft.operationsmanagement/solutions', 'microsoft.authorization/roleassignments', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT811                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT901                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT903                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT921                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.apimanagement/service', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1017                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1018                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1026                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1028                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1035                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.compute/virtualmachinescalesets', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1370                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1371                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1372                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1375                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.insights/diagnosticsettings', 'microsoft.authorization/locks']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1376                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1400                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1402                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1404                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1406                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1408                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1410                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1412                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1414                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1416                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1418                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.machinelearningservices/workspaces/datasets']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1425                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1427                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1429                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1431                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1433                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1435                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerregistry/registries', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.synapse/workspaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1442                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces/computes', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1446                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1447                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1449                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1450                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1451                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.resources/deployments']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1453                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.resources/deployments']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1462                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.containerservice/managedclusters', 'microsoft.storage/storageaccounts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.insights/activitylogalerts', 'microsoft.operationsmanagement/solutions', 'microsoft.authorization/roleassignments', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/azurefirewalls', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/firewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/routetables', 'microsoft.resources/deploymentscripts', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1716                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/virtualnetworks/subnets', 'microsoft.web/hostingenvironments', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/sites/config', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1729                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites/functions', 'microsoft.web/sites']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0109-ARM
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KeyVault_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description         |
|:-----------|:--------------------|
| cloud      | git                 |
| compliance | ['Best Practices '] |
| service    | ['arm']             |
----------------------------------------------------------------


### Test ID - PR-AZR-0130-ARM
Title: Azure Key Vault keys should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-0130-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT905                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/keys/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/keys/0.9/azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0130-ARM
Title: Azure Key Vault keys should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-0130-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0130-ARM
Title: Azure Key Vault keys should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-0130-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1449                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KEYVAULT_KEYS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                             |
|:-----------|:------------------------------------------------------------------------|
| cloud      | git                                                                     |
| compliance | ['PCI-DSS', 'GDPR', 'ISO 27001', 'NIST CSF', 'HIPAA', 'Best Practices'] |
| service    | ['arm']                                                                 |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT507                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT811                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT921                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.apimanagement/service', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1370                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1371                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.operationalinsights/workspaces', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/privateendpoints', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1372                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1491                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/azurefirewalls', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/firewallpolicies', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/routetables', 'microsoft.resources/deploymentscripts', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1729                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites/functions', 'microsoft.web/sites']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0018-ARM
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-0018-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.keyvault/vaults', 'microsoft.network/networkinterfaces', 'microsoft.resources/deployments', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KEYVAULT_SECRETS
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultsecrets.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------

