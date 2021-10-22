# Automated Vulnerability Scan result and Static Code Analysis for Azure Quickstart files (Aug 2021)


## Azure KeyVault Services

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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT64                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                          |
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
| id            | ARM_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.synapse/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.authorization/roleassignments', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/bigdatapools']                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.parameters.json'] |

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
| id            | ARM_TEMPLATE_SNAPSHOT77                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT80                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT90                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT92                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT94                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| id            | ARM_TEMPLATE_SNAPSHOT100                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT102                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                              |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT104                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT105                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                              |
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
| id            | ARM_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.storage/storageaccounts']                                                                                  |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                         |
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
| id            | ARM_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                            |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT118                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT120                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT280                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT322                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachinescalesets/extensions']                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT332                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT360                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT361                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT577                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.operationsmanagement/solutions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.authorization/roleassignments', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.containerregistry/registries', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.containerservice/managedclusters'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT593                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.managedidentity/userassignedidentities']                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT627                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/azurefirewalls', 'microsoft.resources/deploymentscripts', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/routetables', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies'] |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT736                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.web/sites/functions', 'microsoft.web/sites', 'microsoft.keyvault/vaults/secrets', 'microsoft.storage/storageaccounts']                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT751                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.web/hostingenvironments', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites/config', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT757                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT858                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT859                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privateendpoints', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT860                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT864                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/locks', 'microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                  |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT866                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT996                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities']                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1012                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privatednszones', 'microsoft.keyvault/vaults', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.operationsmanagement/solutions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.authorization/roleassignments', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.containerregistry/registries', 'microsoft.network/publicipaddresses', 'microsoft.containerservice/managedclusters'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1194                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT1246                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1326                                                                                                                    |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorArmMS                                                                                                                            |
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
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1794                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT64                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                   |
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
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                          |
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
| id            | ARM_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.synapse/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.authorization/roleassignments', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/bigdatapools']                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.parameters.json'] |

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
| id            | ARM_TEMPLATE_SNAPSHOT77                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT80                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
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
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT90                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT92                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT94                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| id            | ARM_TEMPLATE_SNAPSHOT100                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT102                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                              |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT104                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT105                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                              |
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
| id            | ARM_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                 |
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
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.storage/storageaccounts']                                                                                  |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                         |
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
| id            | ARM_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                            |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT118                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT120                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT280                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT322                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachinescalesets/extensions']                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT332                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT360                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT361                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/networkinterfaces'] |
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
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT577                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.operationsmanagement/solutions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.authorization/roleassignments', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.containerregistry/registries', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.containerservice/managedclusters'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT593                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.managedidentity/userassignedidentities']                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT627                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/azurefirewalls', 'microsoft.resources/deploymentscripts', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/routetables', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies'] |
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
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT736                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.web/sites/functions', 'microsoft.web/sites', 'microsoft.keyvault/vaults/secrets', 'microsoft.storage/storageaccounts']                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT751                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.web/hostingenvironments', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites/config', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT757                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT858                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT859                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privateendpoints', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT860                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT864                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/locks', 'microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                  |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT866                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT996                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities']                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1012                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privatednszones', 'microsoft.keyvault/vaults', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.operationsmanagement/solutions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.authorization/roleassignments', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.containerregistry/registries', 'microsoft.network/publicipaddresses', 'microsoft.containerservice/managedclusters'] |
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
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1194                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT1246                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1326                                                                                                                    |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorArmMS                                                                                                                            |
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
Test Result: **passed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                               |
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
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation, etc.) supported by the key vault objects. It is recommended the key vault be made recoverable by enabling the 'Do Not Purge' and 'Soft Delete' functions. This is in order to prevent loss of encrypted data including storage accounts, SQL databases, and/or dependent services provided by key vault objects (Keys, Secrets, Certificates) etc., as may happen in the case of accidental deletion by a user or from disruptive activity by a malicious user.\

#### Test Details
- eval: data.rule.enableSoftDelete
- id : PR-AZR-0108-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1794                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT64                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.hdinsight/clusters']                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT66                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                          |
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
| id            | ARM_TEMPLATE_SNAPSHOT71                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.synapse/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.authorization/roleassignments', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/bigdatapools']                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.parameters.json'] |

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
| id            | ARM_TEMPLATE_SNAPSHOT77                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT80                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT82                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT84                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT88                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT90                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT92                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT94                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT98                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| id            | ARM_TEMPLATE_SNAPSHOT100                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT102                                                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                                                                              |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT104                                                                                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces/datastores']                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT105                                                                                                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT107                                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT109                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                              |
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
| id            | ARM_TEMPLATE_SNAPSHOT110                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.resources/deployments', 'microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT111                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.storage/storageaccounts']                                                                                  |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT112                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT114                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                         |
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
| id            | ARM_TEMPLATE_SNAPSHOT115                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                            |
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
Test Result: **failed**\
Description : The key vault contains object keys, secrets and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiation\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-0109-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT118                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT120                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT280                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT322                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachinescalesets/extensions']                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT332                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT360                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces']                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT361                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT577                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.operationsmanagement/solutions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.authorization/roleassignments', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.containerregistry/registries', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.containerservice/managedclusters'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT593                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.managedidentity/userassignedidentities']                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT627                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/azurefirewalls', 'microsoft.resources/deploymentscripts', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/routetables', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies'] |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT736                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.web/sites/functions', 'microsoft.web/sites', 'microsoft.keyvault/vaults/secrets', 'microsoft.storage/storageaccounts']                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT751                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.web/hostingenvironments', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites/config', 'microsoft.storage/storageaccounts', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT757                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT858                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT859                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privateendpoints', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT860                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT864                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/locks', 'microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                                                                                  |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT866                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT996                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities']                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1012                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privatednszones', 'microsoft.keyvault/vaults', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.operationalinsights/workspaces', 'microsoft.operationsmanagement/solutions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/bastionhosts', 'microsoft.authorization/roleassignments', 'microsoft.insights/activitylogalerts', 'microsoft.compute/virtualmachines', 'microsoft.containerregistry/registries', 'microsoft.network/publicipaddresses', 'microsoft.containerservice/managedclusters'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1194                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT1246                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
| Title         | Description                                                                                                                                  |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1326                                                                                                                    |
| structure     | filesystem                                                                                                                                   |
| reference     | master                                                                                                                                       |
| source        | gitConnectorArmMS                                                                                                                            |
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
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1789                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1794                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts']                                                                                                               |
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


### Test ID - PR-AZR-0130-ARM
Title: Azure Key Vault keys should have an expiration date\
Test Result: **passed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-0130-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT73                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-encrypted-workspace/prereqs/prereq.azuredeploy.parameters.json'] |

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
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT593                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.managedidentity/userassignedidentities']                                                                               |
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
| id            | ARM_TEMPLATE_SNAPSHOT627                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/bastionhosts', 'microsoft.compute/virtualmachines', 'microsoft.keyvault/vaults', 'microsoft.network/azurefirewalls', 'microsoft.resources/deploymentscripts', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/routetables', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT736                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.web/sites/functions', 'microsoft.web/sites', 'microsoft.keyvault/vaults/secrets', 'microsoft.storage/storageaccounts']                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT757                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults']                                                                                                                                                                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT858                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
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
| id            | ARM_TEMPLATE_SNAPSHOT859                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.network/privateendpoints', 'microsoft.compute/virtualmachines', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT866                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT996                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities']                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1194                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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
| id            | ARM_TEMPLATE_SNAPSHOT1246                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces'] |
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

