# Automated Vulnerability Scan result and Static Code Analysis for Azure Quickstart files (Oct 2021)


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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT221                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.network/applicationgateways', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/virtualmachinescalesets']                                                          |
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
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles', 'microsoft.containerinstance/containergroups']                                            |
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
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT734                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines'] |
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
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT780                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
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
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT798                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
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
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT915                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.apimanagement/service', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.network/privatednszones', 'microsoft.insights/diagnosticsettings']                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1160                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1165                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
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
| id            | ARM_TEMPLATE_SNAPSHOT1463                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                |
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
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
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
| id            | ARM_TEMPLATE_SNAPSHOT1466                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1471                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1472                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1473                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1474                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1475                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1476                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1477                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
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
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1766                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT221                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.network/applicationgateways', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/virtualmachinescalesets']                                                          |
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
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles', 'microsoft.containerinstance/containergroups']                                            |
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
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT734                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines'] |
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
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT780                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
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
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT798                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
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
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
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
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT915                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.apimanagement/service', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.network/privatednszones', 'microsoft.insights/diagnosticsettings']                                                                                                               |
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
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1160                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1165                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
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
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

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
| id            | ARM_TEMPLATE_SNAPSHOT1463                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                |
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
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
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
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

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
| id            | ARM_TEMPLATE_SNAPSHOT1466                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
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
Test Result: **failed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1471                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1472                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1473                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1474                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1475                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1476                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
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
Test Result: **passed**\
Description : Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. SQL injection and cross-site scripting are among the most common attacks.\

#### Test Details
- eval: data.rule.gw_waf
- id : PR-AZR-0012-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1477                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
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
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1766                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                       |
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
| id            | ARM_TEMPLATE_SNAPSHOT221                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.network/applicationgateways', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/virtualmachinescalesets']                                                          |
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
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles', 'microsoft.containerinstance/containergroups']                                            |
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
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
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
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites'] |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT734                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines'] |
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
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT780                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
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
Test Result: **passed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT798                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
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
Test Result: **passed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT915                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.apimanagement/service', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.network/privatednszones', 'microsoft.insights/diagnosticsettings']                                                                                                               |
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
Test Result: **failed**\
Description : Application Gateway allows to set network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.protocol
- id : PR-AZR-0125-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1160                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
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
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1165                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
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
| id            | ARM_TEMPLATE_SNAPSHOT1463                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                |
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
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
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
| id            | ARM_TEMPLATE_SNAPSHOT1466                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
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
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1471                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1472                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                                               |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1473                                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                               |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1474                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1475                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
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
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1476                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
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
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1477                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
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
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                      |
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
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
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
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1766                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                       |
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT221                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.network/applicationgateways', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/virtualmachinescalesets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles', 'microsoft.containerinstance/containergroups']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT734                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **failed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT780                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT798                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **failed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT915                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.apimanagement/service', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.network/privatednszones', 'microsoft.insights/diagnosticsettings']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1160                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1165                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1463                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1466                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1471                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1472                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

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
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1474                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1475                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **failed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1476                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1477                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0060-ARM
Title: Ensure Application Gateway frontendIPConfigurations does not have public ip configured\
Test Result: **passed**\
Description : Application Gateway allows to set public or private ip in frontendIPConfigurations. It is highly recommended to only configure private ip in frontendIPConfigurations.\

#### Test Details
- eval: data.rule.frontendPublicIPConfigurationsDisabled
- id : PR-AZR-0060-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1766                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_4
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT221                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.network/applicationgateways', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/virtualmachinescalesets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles', 'microsoft.containerinstance/containergroups']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT734                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT780                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT798                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **passed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT915                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.apimanagement/service', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.network/privatednszones', 'microsoft.insights/diagnosticsettings']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1160                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1165                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1463                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1466                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1471                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1472                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

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
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1474                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1475                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1476                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1477                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0095-ARM
Title: Ensure Application Gateway Backend is using Https protocol\
Test Result: **failed**\
Description : Application Gateway allows to set backend network protocols Http and Https. It is highly recommended to use Https protocol for secure connections.\

#### Test Details
- eval: data.rule.backend_https_protocol_enabled
- id : PR-AZR-0095-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1766                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_5
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT221                                                                                                                                                                                                                                                                                                        |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.insights/autoscalesettings', 'microsoft.network/applicationgateways', 'microsoft.sql/servers', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/virtualmachinescalesets']                                                          |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/lansa/lansa-vmss-windows-autoscale-sql-database/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                               |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT584                                                                                                                                                                                                                                                                  |
| structure     | filesystem                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.network/networkprofiles', 'microsoft.containerinstance/containergroups']                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/application-workloads/wordpress/aci-wordpress-vnet/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                   |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT608                                                                                                                                                                                                                                      |
| structure     | filesystem                                                                                                                                                                                                                                                    |
| reference     | master                                                                                                                                                                                                                                                        |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                   |
| collection    | armtemplate                                                                                                                                                                                                                                                   |
| type          | arm                                                                                                                                                                                                                                                           |
| region        |                                                                                                                                                                                                                                                               |
| resourceTypes | ['microsoft.resources/deployments', 'microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/application-gateway-demo-setup/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT706                                                                                                                                                                                                                                                                                                            |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.sql/servers', 'microsoft.cache/redis', 'microsoft.network/publicipaddresses', 'microsoft.cdn/profiles', 'microsoft.network/virtualnetworks/subnets', 'microsoft.insights/components', 'microsoft.web/serverfarms', 'microsoft.web/sites'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/e-shop-website-with-ilb-ase/azuredeploy.parameters.json']                                                                             |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                |
|:--------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT734                                                                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                 |
| reference     | master                                                                                                                                                                                                                                                                                                                                                     |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                |
| type          | arm                                                                                                                                                                                                                                                                                                                                                        |
| region        |                                                                                                                                                                                                                                                                                                                                                            |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.storage/storageaccounts', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.network/loadbalancers', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines'] |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/demos/multi-tier-service-networking/azuredeploy.parameters.json']                                                                                                |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                          |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT780                                                                                                             |
| structure     | filesystem                                                                                                                           |
| reference     | master                                                                                                                               |
| source        | gitConnectorAzureQuickStart                                                                                                          |
| collection    | armtemplate                                                                                                                          |
| type          | arm                                                                                                                                  |
| region        |                                                                                                                                      |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                            |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/parameterized-linked-templates/nested/paramappgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT798                                                                                                                                    |
| structure     | filesystem                                                                                                                                                  |
| reference     | master                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                 |
| type          | arm                                                                                                                                                         |
| region        |                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/sql-injection-attack-prevention/nested/microsoft.network/applicationgateways.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                      |
|:--------------|:-------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT886                                                                                                                         |
| structure     | filesystem                                                                                                                                       |
| reference     | master                                                                                                                                           |
| source        | gitConnectorAzureQuickStart                                                                                                                      |
| collection    | armtemplate                                                                                                                                      |
| type          | arm                                                                                                                                              |
| region        |                                                                                                                                                  |
| resourceTypes | ['microsoft.network/applicationgateways']                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/demos/xss-attack-prevention/nested/microsoft.network/applicationgateway.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT915                                                                                                                                                                                                                                                                                                                                                              |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.apimanagement/service', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.insights/components', 'microsoft.network/privatednszones', 'microsoft.insights/diagnosticsettings']                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.apimanagement/api-management-create-with-internal-vnet-application-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1160                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                              |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-ubuntu-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                       |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1165                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.compute/virtualmachinescalesets', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.compute/vmss-windows-app-gateway/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1463                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/networksecuritygroups', 'microsoft.network/virtualnetworks', 'microsoft.compute/availabilitysets', 'microsoft.network/networkinterfaces', 'microsoft.compute/virtualmachines']                                |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-2vms-iis-ssl/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                           |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1464                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                        |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

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

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                       |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1466                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-multihosting/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                         |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1467                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-path-override/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                         |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1468                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-probe/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                 |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1469                                                                                                                                                                                                                                                                                   |
| structure     | filesystem                                                                                                                                                                                                                                                                                                  |
| reference     | master                                                                                                                                                                                                                                                                                                      |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                 |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                 |
| type          | arm                                                                                                                                                                                                                                                                                                         |
| region        |                                                                                                                                                                                                                                                                                                             |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                         |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1470                                                                                                                                                                                                                                                                                                           |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                          |
| reference     | master                                                                                                                                                                                                                                                                                                                              |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                         |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                         |
| type          | arm                                                                                                                                                                                                                                                                                                                                 |
| region        |                                                                                                                                                                                                                                                                                                                                     |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                               |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-public-ip-ssl-offload/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                               |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1471                                                                                                                                                                                                                                                                                 |
| structure     | filesystem                                                                                                                                                                                                                                                                                                |
| reference     | master                                                                                                                                                                                                                                                                                                    |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                               |
| collection    | armtemplate                                                                                                                                                                                                                                                                                               |
| type          | arm                                                                                                                                                                                                                                                                                                       |
| region        |                                                                                                                                                                                                                                                                                                           |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-redirect/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1472                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-rewrite/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

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
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                     |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-custom/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **failed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1474                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                             |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-sslpolicy-predefined/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                           |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1475                                                                                                                                                                                                                                                                                                             |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                            |
| reference     | master                                                                                                                                                                                                                                                                                                                                |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                           |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                           |
| type          | arm                                                                                                                                                                                                                                                                                                                                   |
| region        |                                                                                                                                                                                                                                                                                                                                       |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                                 |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-url-path-based-routing/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                     |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1476                                                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-v2-autoscale-create/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1477                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                           |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-waf/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                                                       |
|:--------------|:----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1478                                                                                                                                                                                                                                                                                                         |
| structure     | filesystem                                                                                                                                                                                                                                                                                                                        |
| reference     | master                                                                                                                                                                                                                                                                                                                            |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                                                       |
| collection    | armtemplate                                                                                                                                                                                                                                                                                                                       |
| type          | arm                                                                                                                                                                                                                                                                                                                               |
| region        |                                                                                                                                                                                                                                                                                                                                   |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.dbformysql/servers', 'microsoft.web/serverfarms', 'microsoft.resources/deployments', 'microsoft.web/sites']                                                                                      |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapp-iprestriction/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                             |
|:--------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1480                                                                                                                                                                                                                                                                               |
| structure     | filesystem                                                                                                                                                                                                                                                                                              |
| reference     | master                                                                                                                                                                                                                                                                                                  |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                             |
| collection    | armtemplate                                                                                                                                                                                                                                                                                             |
| type          | arm                                                                                                                                                                                                                                                                                                     |
| region        |                                                                                                                                                                                                                                                                                                         |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks']                                                                                                                                                                                   |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.network/application-gateway-webapps/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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


### Test ID - PR-AZR-0099-ARM
Title: Ensure Application Gateway secret certificates stores in keyvault\
Test Result: **passed**\
Description : This policy will identify application gateways which dont have ssl certificates stored in keyvalut and alert\

#### Test Details
- eval: data.rule.secret_certificate_is_in_keyvalut
- id : PR-AZR-0099-ARM

#### Snapshots
| Title         | Description                                                                                                                                                                                                                                                                                     |
|:--------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id            | ARM_TEMPLATE_SNAPSHOT1766                                                                                                                                                                                                                                                                       |
| structure     | filesystem                                                                                                                                                                                                                                                                                      |
| reference     | master                                                                                                                                                                                                                                                                                          |
| source        | gitConnectorAzureQuickStart                                                                                                                                                                                                                                                                     |
| collection    | armtemplate                                                                                                                                                                                                                                                                                     |
| type          | arm                                                                                                                                                                                                                                                                                             |
| region        |                                                                                                                                                                                                                                                                                                 |
| resourceTypes | ['microsoft.network/applicationgateways', 'microsoft.network/publicipaddresses', 'microsoft.network/virtualnetworks', 'microsoft.web/serverfarms', 'microsoft.web/sites']                                                                                                                       |
| paths         | ['https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.json', 'https://github.com/Azure/azure-quickstart-templates/tree/master/quickstarts/microsoft.web/web-app-with-app-gateway-v2/azuredeploy.parameters.json'] |

- masterTestId: TEST_APPLICATION_GATEWAYS_6
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

