# Automated Vulnerability Scan result and Static Code Analysis for Azure QuickStart Templates (Jan 2022)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20AKS.md
#### Application Gateway (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20Application%20Gateway%20(Part1).md
#### Application Gateway (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20Application%20Gateway%20(Part2).md
#### KV (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20KV%20(Part1).md
#### KV (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20KV%20(Part2).md
#### KV (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20KV%20(Part3).md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20PostgreSQL.md
#### SQL Servers: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20SQL%20Servers.md
#### VM (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20VM%20(Part1).md
#### VM (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20VM%20(Part2).md
#### VM (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20VM%20(Part3).md
#### VM (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20VM%20(Part4).md
#### VM (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20VM%20(Part5).md
#### VM (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Jan-2022/output23012022%20Azure%20VM%20(Part6).md

## Azure Key Vault (Part2) Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description               |
|:----------|:--------------------------|
| timestamp | 1642955527478             |
| snapshot  | master-snapshot_gen       |
| container | scenario-azure-quickStart |
| test      | master-test.json          |

## Results

### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1434                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1436                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1438                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1442                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1444                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1450                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.machinelearningservices/workspaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1456                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1457                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1458                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1459                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1460                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1461                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/applicationgateways', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1481                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1509                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/azurefirewalls', 'microsoft.network/routetables', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.resources/deploymentscripts', 'microsoft.network/publicipaddresses', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/firewallpolicies', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **passed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1723                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1745                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites', 'microsoft.web/sites/config', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/hostingenvironments', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1759                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1767                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/networksecuritygroups', 'microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/serverfarms', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/privatednszones/a', 'microsoft.apimanagement/service/loggers', 'microsoft.apimanagement/service'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-003
Title: Key vault should have purge protection enabled\
Test Result: **failed**\
Description : The key vault contains object keys, secrets, and certificates. Accidental unavailability of a key vault can cause immediate data loss or loss of security functions (authentication, validation, verification, non-repudiationK\

#### Test Details
- eval: data.rule.enablePurgeProtection
- id : PR-AZR-ARM-KV-003

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1821                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: PR-AZR-ARM-KV-003
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: High

tags
| Title      | Description       |
|:-----------|:------------------|
| cloud      | git               |
| compliance | ['Best Practice'] |
| service    | ['arm']           |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-ARM-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT908                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults/keys']                                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/keys/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/keys/0.9/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-004
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-ARM-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1458                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-004
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-ARM-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1459                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-004
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-004
Title: Azure Key Vault keys should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault keys that do not have an expiration date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_keys_expire
- id : PR-AZR-ARM-KV-004

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1723                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-004
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/keyvaultkeys.rego)
- severity: High

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT509                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT814                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT925                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1379                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1380                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/networksecuritygroups', 'microsoft.operationalinsights/workspaces', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privatednszones/virtualnetworklinks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1381                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.maps/accounts', 'microsoft.maps/accounts/providers/roleassignments', 'microsoft.keyvault/vaults/secrets']                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                            |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                             |
| reference     | master                                                                                                                                                                                                                                                                 |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                            |
| collection    | armtemplate                                                                                                                                                                                                                                                            |
| type          | arm                                                                                                                                                                                                                                                                    |
| region        |                                                                                                                                                                                                                                                                        |
| resourceTypes | ['microsoft.maps/accounts', 'microsoft.maps/accounts/providers/roleassignments', 'microsoft.keyvault/vaults/secrets']                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1481                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1509                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/azurefirewalls', 'microsoft.network/routetables', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.resources/deploymentscripts', 'microsoft.network/publicipaddresses', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/firewallpolicies', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1759                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1767                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/networksecuritygroups', 'microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/serverfarms', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/privatednszones/a', 'microsoft.apimanagement/service/loggers', 'microsoft.apimanagement/service'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-005
Title: Azure Key Vault secrets should have an expiration date\
Test Result: **failed**\
Description : This policy identifies Azure Key Vault secrets that do not have an expiratiSon date. As a best practice, set an expiration date for each secret and rotate the secret regularly.\

#### Test Details
- eval: data.rule.kv_expire
- id : PR-AZR-ARM-KV-005

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1821                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: PR-AZR-ARM-KV-005
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


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

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

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT509                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **passed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT603                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/applicationgateways', 'microsoft.network/natgateways', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/publicipprefixes', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **passed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT814                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT904                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT906                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT925                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1022                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1023                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1031                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1033                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1040                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1379                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1380                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/networksecuritygroups', 'microsoft.operationalinsights/workspaces', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privatednszones/virtualnetworklinks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1381                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1384                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.authorization/locks']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1385                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1409                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.hdinsight/clusters', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1411                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1413                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1425                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1427                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1428                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1430                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1432                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1434                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1436                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1438                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1442                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1444                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1450                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.machinelearningservices/workspaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1456                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1457                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1458                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1459                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1460                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1461                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **passed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/applicationgateways', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1481                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1509                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/azurefirewalls', 'microsoft.network/routetables', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.resources/deploymentscripts', 'microsoft.network/publicipaddresses', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/firewallpolicies', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1723                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1745                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites', 'microsoft.web/sites/config', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/hostingenvironments', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1759                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **passed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1767                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/networksecuritygroups', 'microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/serverfarms', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/privatednszones/a', 'microsoft.apimanagement/service/loggers', 'microsoft.apimanagement/service'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-006
Title: Azure Key Vault Network Access default action should be 'deny'\
Test Result: **failed**\
Description : Azure Key Vault Network Access default action should be 'deny' so that it's not accessible over the public internet. This can reduce data leakage risks.\

#### Test Details
- eval: data.rule.keyvault_Acl
- id : PR-AZR-ARM-KV-006

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1821                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: PR-AZR-ARM-KV-006
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

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

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT509                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT603                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/applicationgateways', 'microsoft.network/natgateways', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/publicipprefixes', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT814                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT904                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT906                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT925                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1022                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1023                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/networkinterfaces']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1031                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1033                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1040                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1378                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1379                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1380                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/networksecuritygroups', 'microsoft.operationalinsights/workspaces', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/privatednszones/virtualnetworklinks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1381                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1384                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.authorization/locks']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1385                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1409                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.hdinsight/clusters', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1411                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1413                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1425                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1427                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1428                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1430                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1432                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1434                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1436                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1438                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1442                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1444                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.containerregistry/registries', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1450                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.synapse/workspaces/sqlpools', 'microsoft.synapse/workspaces', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.authorization/roleassignments', 'microsoft.storage/storageaccounts', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.machinelearningservices/workspaces']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1456                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1457                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1458                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1459                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1460                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1461                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1465                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces', 'microsoft.containerregistry/registries']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                          |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                           |
| reference     | master                                                                                                                                                                                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                          |
| type          | arm                                                                                                                                                                                                                                                                                                  |
| region        |                                                                                                                                                                                                                                                                                                      |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.maps/maps-use-sas/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/applicationgateways', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1481                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1509                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/azurefirewalls', 'microsoft.network/routetables', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.resources/deploymentscripts', 'microsoft.network/publicipaddresses', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.network/firewallpolicies', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/bastionhosts', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1723                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.managedidentity/userassignedidentities']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1745                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/virtualnetworkgateways', 'microsoft.web/sites', 'microsoft.web/sites/config', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.sql/servers', 'microsoft.insights/components', 'microsoft.web/hostingenvironments', 'microsoft.storage/storageaccounts', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones/virtualnetworklinks'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1759                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.keyvault/vaults', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **failed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1767                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.web/sites/config', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.apimanagement/service/diagnostics', 'microsoft.network/networksecuritygroups', 'microsoft.insights/diagnosticsettings', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.web/serverfarms', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.network/privatednszones/a', 'microsoft.apimanagement/service/loggers', 'microsoft.apimanagement/service'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/private-webapp-with-app-gateway-and-apim/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-007
Title: Azure Key Vault Trusted Microsoft Services access should be enabled\
Test Result: **passed**\
Description : Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are any combination of Logging, Metrics, AzureServices (For example, 'Logging, Metrics'), or None to bypass none of those traffics. - None, Logging, Metrics, AzureServices.\

#### Test Details
- eval: data.rule.keyvault_bypass
- id : PR-AZR-ARM-KV-007

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1821                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: PR-AZR-ARM-KV-007
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

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

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT509                                                                                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/proximityplacementgroups', 'microsoft.network/networkinterfaces', 'microsoft.keyvault/vaults/secrets'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT603                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/applicationgateways', 'microsoft.network/natgateways', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.network/publicipprefixes', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT787                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.insights/activitylogalerts', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints', 'microsoft.operationsmanagement/solutions', 'microsoft.network/bastionhosts', 'microsoft.containerregistry/registries', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.compute/virtualmachines/extensions', 'microsoft.containerservice/managedclusters', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones', 'microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT814                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts', 'microsoft.keyvault/vaults/secrets']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT904                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.insights/components', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.machinelearningservices/workspaces']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT906                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT925                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.authorization/roleassignments', 'microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: PR-AZR-ARM-KV-008
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description   |
|:-----------|:--------------|
| cloud      | git           |
| compliance | []            |
| service    | ['arm']       |
----------------------------------------------------------------

