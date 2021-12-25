# Automated Vulnerability Scan result and Static Code Analysis for Azure QuickStart Templates (Dec 2021)

## All Services

#### AKS: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20AKS.md
#### Application Gateways (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20Application%20Gateways%20(Part1).md
#### Application Gateways (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20Application%20Gateways%20(Part2).md
#### KV (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part1).md
#### KV (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part2).md
#### KV (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20KV%20(Part3).md
#### PostgreSQL: https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20PostgreSQL.md
#### VM (Part1): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part1).md
#### VM (Part2): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part2).md
#### VM (Part3): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part3).md
#### VM (Part4): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part4).md
#### VM (Part5): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part5).md
#### VM (Part6): https://github.com/prancer-io/prancer-compliance-test/tree/master/docs/sca-report/azure-quickstart/Dec-2021/output12232021%20Azure%20VM%20(Part6).md

## Azure KeyVault (Part3) Services

Source Repository: https://github.com/Azure/azure-quickstart-templates

Scan engine: **Prancer Framework** (https://www.prancer.io)

Compliance Database: https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac

## Compliance run Meta Data
| Title     | Description                |
|:----------|:---------------------------|
| timestamp | 1640441685242              |
| snapshot  | master-snapshot_gen        |
| container | scenario-azure-quick-start |
| test      | master-test.json           |

## Results

### Test ID - PR-AZR-ARM-KV-008
Title: Key Vault should use a virtual network service endpoint\
Test Result: **failed**\
Description : This policy audits any Key Vault not configured to use a virtual network service endpoint.\

#### Test Details
- eval: data.rule.keyvault_service_endpoint
- id : PR-AZR-ARM-KV-008

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1375                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults']                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1376                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.operationalinsights/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1377                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1380                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.authorization/locks', 'microsoft.storage/storageaccounts']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1381                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1405                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.hdinsight/clusters', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1407                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1409                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1411                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1413                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1424                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1426                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1428                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1430                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1432                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1434                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1436                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1438                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1446                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.synapse/workspaces', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.storage/storageaccounts']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1453                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1454                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1455                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1456                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1457                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1460                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1461                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgateways', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1473                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1499                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/routetables', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/azurefirewalls', 'microsoft.network/publicipaddresses', 'microsoft.resources/deploymentscripts', 'microsoft.network/bastionhosts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1713                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1735                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.insights/components', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.web/sites', 'microsoft.web/hostingenvironments', 'microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1749                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_8
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
| id            | ARM_TEMPLATE_SNAPSHOT1810                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.compute/proximityplacementgroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KeyVault_8
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


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

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

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

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
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.compute/proximityplacementgroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **passed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT601                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.network/natgateways', 'microsoft.network/publicipprefixes', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgateways', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **passed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT785                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT812                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.storage/storageaccounts']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT902                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT904                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT923                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1019                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1020                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1028                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1030                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1037                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1374                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1375                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults']                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **passed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1376                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.operationalinsights/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1377                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1380                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.authorization/locks', 'microsoft.storage/storageaccounts']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1381                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1405                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.hdinsight/clusters', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1407                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1409                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1411                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1413                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1424                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1426                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

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
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1430                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

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
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1434                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

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
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1438                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1446                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.synapse/workspaces', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.storage/storageaccounts']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1453                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1454                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1455                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1456                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1457                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1460                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1461                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **passed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgateways', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1473                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1499                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/routetables', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/azurefirewalls', 'microsoft.network/publicipaddresses', 'microsoft.resources/deploymentscripts', 'microsoft.network/bastionhosts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1713                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1735                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.insights/components', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.web/sites', 'microsoft.web/hostingenvironments', 'microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1749                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-009
Title: Configure Azure Key Vaults with private endpoints\
Test Result: **failed**\
Description : Private endpoints connect your virtual networks to Azure services without a public IP address at the source or destination. By mapping private endpoints to key vault, you can reduce data leakage risks. Learn more about private links at: https://aka.ms/akvprivatelink.\

#### Test Details
- eval: data.rule.kv_private_endpoint
- id : PR-AZR-ARM-KV-009

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1810                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.compute/proximityplacementgroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KeyVault_9
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

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

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

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
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.compute/proximityplacementgroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/sas/sas9.4-viya/sas9.4-viya/azuredeploy.parameters.json']                                                                                                     |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT601                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.network/natgateways', 'microsoft.network/publicipprefixes', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgateways', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/aks-nat-agic/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT785                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/private-aks-cluster-with-public-dns-zone/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT812                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults', 'microsoft.resources/deploymentscripts', 'microsoft.storage/storageaccounts']                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/storage-import-zipped-vhds/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT902                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/machine-learning-workspace/0.9/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                     |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT904                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/modules/Microsoft.KeyVault/vaults/1.0/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT923                                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.apimanagement/service', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults']                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1019                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1020                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-create-new-vm-gallery-image-managed-disks/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1028                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-vmss-windows/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1030                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.compute/virtualmachines/extensions', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-running-windows-vm/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1037                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets/extensions', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/encrypt-vmss-windows-jumpbox/azuredeploy.parameters.json']                       |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1374                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1375                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults']                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-create-rbac/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1376                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.operationalinsights/workspaces', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/privateendpoints', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-private-endpoint/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                               |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1377                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-secret-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1380                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.insights/diagnosticsettings', 'microsoft.keyvault/vaults', 'microsoft.authorization/locks', 'microsoft.storage/storageaccounts']                                                                                                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/key-vault-with-logging-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1381                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.keyvault/keyvault-add-access-policy/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1405                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.hdinsight/clusters', 'microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-attach-hdi/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1407                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-akscompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1409                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-amlcompute/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1411                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-compute-create-computeinstance/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1413                                                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1415                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-file-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-relative-path/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1419                                                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-sql-query/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                             |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1421                                                                                                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-tabular-from-web-url/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1423                                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.machinelearningservices/workspaces/datasets', 'microsoft.keyvault/vaults', 'microsoft.machinelearningservices/workspaces/datastores', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dataset-create-workspace-multiple-dataset-datastore/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1424                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1426                                                                                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-adls-gen2/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

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
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-blob/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1430                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-dbfs/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

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
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-file/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1434                                                                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-mysql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

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
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-psql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1438                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-datastore-create-sql/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1440                                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.containerregistry/registries', 'microsoft.storage/storageaccounts']                                                                                                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-dependencies-role-assignment/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1446                                                                                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.insights/components', 'microsoft.machinelearningservices/workspaces', 'microsoft.synapse/workspaces/bigdatapools', 'microsoft.synapse/workspaces', 'microsoft.authorization/roleassignments', 'microsoft.keyvault/vaults', 'microsoft.resources/deployments', 'microsoft.synapse/workspaces/sqlpools', 'microsoft.storage/storageaccounts']                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-linkedservice-create/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                             |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1448                                                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.machinelearningservices/workspaces/computes', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                  |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-private-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1452                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                         |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                              |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1453                                                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                               |
| reference     | master                                                                                                                                                                                                                                                                                                                                   |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                              |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                              |
| type          | arm                                                                                                                                                                                                                                                                                                                                      |
| region        |                                                                                                                                                                                                                                                                                                                                          |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1454                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                    |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1455                                                                                                                                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                     |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                         |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                    |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                    |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                            |
| region        |                                                                                                                                                                                                                                                                                                                                                                                |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults']                                                                                                                                                                                                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/prereqs/prereq.azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                   |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1456                                                                                                                                                                                                                                                                                                                     |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1457                                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                       |
| reference     | master                                                                                                                                                                                                                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                      |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                      |
| type          | arm                                                                                                                                                                                                                                                                                                                                              |
| region        |                                                                                                                                                                                                                                                                                                                                                  |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                                                                                                                    |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-cmk/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1460                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                        |
|:--------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1461                                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                         |
| reference     | master                                                                                                                                                                                                                                                                                                                                             |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                        |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                        |
| type          | arm                                                                                                                                                                                                                                                                                                                                                |
| region        |                                                                                                                                                                                                                                                                                                                                                    |
| resourceTypes | ['microsoft.machinelearningservices/workspaces', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.resources/deployments', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.machinelearningservices/machine-learning-workspace-vnet/azuredeploy.parameters.us.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.authorization/roleassignments', 'microsoft.compute/virtualmachines', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.containerregistry/registries', 'microsoft.operationsmanagement/solutions', 'microsoft.network/publicipaddresses', 'microsoft.network/bastionhosts', 'microsoft.operationalinsights/workspaces', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.network/applicationgatewaywebapplicationfirewallpolicies', 'microsoft.compute/virtualmachines/extensions', 'microsoft.network/networkinterfaces', 'microsoft.network/applicationgateways', 'microsoft.network/privatednszones', 'microsoft.insights/activitylogalerts', 'microsoft.containerservice/managedclusters', 'microsoft.network/privateendpoints', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/aks-application-gateway-ingress-controller/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1473                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.managedidentity/userassignedidentities', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.network/publicipaddresses', 'microsoft.network/applicationgateways']                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-key-vault-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1499                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/routetables', 'microsoft.network/firewallpolicies/rulecollectiongroups', 'microsoft.managedidentity/userassignedidentities', 'microsoft.network/firewallpolicies', 'microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.keyvault/vaults', 'microsoft.compute/virtualmachines/extensions', 'microsoft.compute/virtualmachines', 'microsoft.network/networkinterfaces', 'microsoft.network/azurefirewalls', 'microsoft.network/publicipaddresses', 'microsoft.resources/deploymentscripts', 'microsoft.network/bastionhosts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/azurefirewall-premium/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                     |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1713                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.keyvault/vaults/keys', 'microsoft.keyvault/vaults', 'microsoft.managedidentity/userassignedidentities', 'microsoft.storage/storageaccounts']                                                                                                                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.storage/storage-blob-encryption-with-cmk/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1735                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.sql/servers', 'microsoft.web/sites/config', 'microsoft.network/virtualnetworks/subnets', 'microsoft.network/privateendpoints', 'microsoft.insights/components', 'microsoft.network/virtualnetworks', 'microsoft.network/privatednszones/virtualnetworklinks', 'microsoft.keyvault/vaults', 'microsoft.network/privatednszones', 'microsoft.web/serverfarms', 'microsoft.compute/virtualmachines', 'microsoft.web/sites', 'microsoft.web/hostingenvironments', 'microsoft.network/networkinterfaces', 'microsoft.network/virtualnetworkgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/privateendpoints/privatednszonegroups', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/asev2-appservice-sql-vpngw/azuredeploy.parameters.json']                                                                                                                                                                                                                                                                                                                                                                                                       |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1749                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.web/sites/functions', 'microsoft.keyvault/vaults', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.insights/components', 'microsoft.storage/storageaccounts']                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/function-http-trigger/azuredeploy.parameters.json'] |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------


### Test ID - PR-AZR-ARM-KV-010
Title: Ensure Azure KeyVault don't have public network access enabled\
Test Result: **failed**\
Description : Always use Private Endpoint for Azure KeyVault\

#### Test Details
- eval: data.rule.kv_public_access_disabled
- id : PR-AZR-ARM-KV-010

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                                 |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1810                                                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.keyvault/vaults/secrets', 'microsoft.network/virtualnetworks', 'microsoft.network/networksecuritygroups', 'microsoft.keyvault/vaults', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.resources/deployments', 'microsoft.network/networkinterfaces', 'microsoft.network/publicipaddresses', 'microsoft.compute/proximityplacementgroups'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/sas9.4-viya/azuredeploy.parameters.json']                                                                                                                                                                                 |

- masterTestId: TEST_KeyVault_10
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/KeyVault.rego)
- severity: Medium

tags
| Title      | Description        |
|:-----------|:-------------------|
| cloud      | git                |
| compliance | ['Best Practices'] |
| service    | ['arm']            |
----------------------------------------------------------------

