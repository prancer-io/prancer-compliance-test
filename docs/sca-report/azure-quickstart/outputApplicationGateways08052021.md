# Automated Vulnerability Scan result and Static Code Analysis for Azure Quickstart files (Aug 2021)


## Azure Application Gateways Services

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

### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT299                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT377                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT553                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT555                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT557                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT563                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT567                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT570                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT571                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT591                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.compute/availabilitysets', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT599                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT614                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT619                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT630                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT639                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT644                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT647                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT649                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT725                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT760                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/privatednszones', 'microsoft.apimanagement/service', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/diagnosticsettings']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT884                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT939                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1107                                                                                                                        |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1121                                                                                                            |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                    |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1163                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.compute/availabilitysets', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1167                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1272                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.containerinstance/containergroups', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0011-ARM
Title: Azure Application Gateway should not allow TLSv1.1 or lower\
Test Result: **failed**\
Description : Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted. Application gateway supports both TLS termination at the gateway as well as end to end TLS encryption. The minimum allowed TLS version should be 1.2\

#### Test Details
- eval: data.rule.gw_tls
- id : PR-AZR-0011-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/loadbalancers', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_1
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                                      |
|:-----------|:-----------------------------------------------------------------|
| cloud      | git                                                              |
| compliance | ['CIS', 'CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                          |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT299                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT377                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT553                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT555                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT557                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT563                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT567                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT570                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT571                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT591                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.compute/availabilitysets', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT599                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT614                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT619                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT630                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT639                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT644                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT647                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT649                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT725                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT760                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/privatednszones', 'microsoft.apimanagement/service', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/diagnosticsettings']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT884                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT939                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1107                                                                                                                        |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1121                                                                                                            |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                    |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1163                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.compute/availabilitysets', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1167                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1272                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.containerinstance/containergroups', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0012-ARM
Title: Azure Application Gateway should have the Web application firewall (WAF) enabled\
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/loadbalancers', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_2
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT299                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT377                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.compute/virtualmachinescalesets', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT553                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT555                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT557                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT563                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT567                                                                                                                                                                                                                                                                                    |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT570                                                                                                                                                                                                                                                                                |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT571                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT591                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.compute/availabilitysets', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT599                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT614                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT619                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT630                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT639                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT644                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT647                                                                                                                                                                                                                                                                                                          |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT649                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT725                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.web/serverfarms', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT760                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/privatednszones', 'microsoft.apimanagement/service', 'microsoft.insights/components', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/diagnosticsettings']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT884                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorArmMS                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT939                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1107                                                                                                                        |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorArmMS                                                                                                                                |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1121                                                                                                            |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorArmMS                                                                                                                    |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1163                                                                                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                                          |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/networksecuritygroups', 'microsoft.storage/storageaccounts', 'microsoft.compute/virtualmachines', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.compute/availabilitysets', 'microsoft.network/loadbalancers', 'microsoft.network/virtualnetworks', 'microsoft.network/networkinterfaces'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1167                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/virtualnetworks/subnets', 'microsoft.web/serverfarms', 'microsoft.insights/components', 'microsoft.web/sites', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.cache/redis', 'microsoft.sql/servers', 'microsoft.storage/storageaccounts'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1272                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.storage/storageaccounts', 'microsoft.containerinstance/containergroups', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------


### Test ID - PR-AZR-0125-ARM
Title: Ensure Application Gateway is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1417                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorArmMS                                                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/loadbalancers', 'microsoft.sql/servers', 'microsoft.network/virtualnetworks', 'microsoft.compute/virtualmachinescalesets', 'microsoft.insights/autoscalesettings']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_3
- masterSnapshotId: ['ARM_TEMPLATE_SNAPSHOT']
- type: rego
- rule: file(https://github.com/prancer-io/prancer-compliance-test/tree/master/azure/iac/applicationgateways.rego)
- severity: Medium

tags
| Title      | Description                                               |
|:-----------|:----------------------------------------------------------|
| cloud      | git                                                       |
| compliance | ['CSA-CCM', 'HITRUST', 'NIST 800', 'NIST CSF', 'PCI-DSS'] |
| service    | ['arm']                                                   |
----------------------------------------------------------------

